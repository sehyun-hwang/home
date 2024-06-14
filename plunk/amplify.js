import { Amplify, generateClient } from './dist.js';

const userPoolId = 'ap-northeast-1_qoqGcg329';
const [region] = userPoolId.split('_');
export const username = 'home';

Amplify.configure({
  Auth: {
    Cognito: {
      region,
      userPoolId,
      userPoolClientId: '7e934gsd83ncu0fq7g9g8k2jrl',
    },
  },
  API: {
    GraphQL: {
      endpoint:
        'https://rjzltmvlozeyno47h53hozb2hi.appsync-api.ap-northeast-1.amazonaws.com/graphql',
      region: 'ap-northeast-1',
      defaultAuthMode: 'userPool',
    },
  },
});

const SubscribeQuery = `subscription Subscribe($name: String!) {
  subscribe(name: $name) {
    name
    data
    __typename
  }
}`;

export const PublishQuery = `mutation PublishData($data: AWSJSON!) {
  publish(data: $data, name: "channel") {
    data
    name
  }
}`;

const client = generateClient({
  authMode: 'userPool',
});

export const subscribeAppSync = eventTarget => client
    .graphql({
      query: SubscribeQuery,
      variables: {
        name: 'channel',
      },
    })
    .subscribe({
      next: ({
        data: {
          subscribe: { data },
        },
      }) => {
        console.log(data);
        const detail = JSON.parse(data);
        eventTarget.dispatchEvent(
          new CustomEvent('message', {
            detail,
          })
        );
      },
      error: (error) => console.warn(error),
    });